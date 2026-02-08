//! Session Persistence Module
//!
//! Saves and restores application state between sessions.
//! Supports saving request history, proxy history, collections, and settings.

#![allow(dead_code)]

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Session data that persists between runs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Version for format compatibility
    pub version: u32,
    /// Timestamp when session was saved
    pub saved_at: SystemTime,
    /// Request history
    pub request_history: Vec<HistoryEntry>,
    /// Proxy history (limited to recent entries)
    pub proxy_history: Vec<ProxyHistoryEntry>,
    /// Environment variables
    pub environments: Vec<Environment>,
    /// Active environment index
    pub active_environment: Option<usize>,
    /// Last used URL
    pub last_url: Option<String>,
    /// Last used method
    pub last_method: Option<String>,
    /// Fuzzer request template
    pub fuzzer_template: Option<String>,
    /// Window/panel sizes (for future layout persistence)
    pub layout: Option<LayoutState>,
}

impl Default for SessionData {
    fn default() -> Self {
        Self {
            version: 1,
            saved_at: SystemTime::now(),
            request_history: Vec::new(),
            proxy_history: Vec::new(),
            environments: vec![
                Environment::default_local(),
                Environment::default_dev(),
                Environment::default_staging(),
                Environment::default_prod(),
            ],
            active_environment: Some(0),
            last_url: None,
            last_method: None,
            fuzzer_template: None,
            layout: None,
        }
    }
}

impl SessionData {
    /// Create new session data
    pub fn new() -> Self {
        Self::default()
    }

    /// Load session from a file
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open session file: {}", path.display()))?;
        let reader = BufReader::new(file);
        let session: SessionData = serde_json::from_reader(reader)
            .with_context(|| "Failed to parse session file")?;
        Ok(session)
    }

    /// Save session to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        let file = File::create(path)
            .with_context(|| format!("Failed to create session file: {}", path.display()))?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .with_context(|| "Failed to write session file")?;
        Ok(())
    }

    /// Get the default session file path
    pub fn default_path() -> Result<PathBuf> {
        use directories::ProjectDirs;

        let data_dir = ProjectDirs::from("com", "ancarna", "ancarna")
            .map(|dirs| dirs.data_local_dir().to_path_buf())
            .unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(|h| PathBuf::from(h).join(".local").join("share").join("ancarna"))
                    .unwrap_or_else(|_| PathBuf::from(".").join("ancarna"))
            });

        Ok(data_dir.join("session.json"))
    }

    /// Load from default path or create new
    pub fn load_or_default() -> Self {
        match Self::default_path() {
            Ok(path) => {
                if path.exists() {
                    match Self::load(&path) {
                        Ok(session) => {
                            tracing::info!("Loaded session from {}", path.display());
                            return session;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load session: {}, using defaults", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to determine session path: {}", e);
            }
        }
        Self::default()
    }

    /// Save to default path
    pub fn save_default(&mut self) -> Result<()> {
        self.saved_at = SystemTime::now();
        let path = Self::default_path()?;
        self.save(&path)?;
        tracing::info!("Saved session to {}", path.display());
        Ok(())
    }

    /// Add a history entry (keeping max 100)
    pub fn add_history(&mut self, entry: HistoryEntry) {
        self.request_history.insert(0, entry);
        if self.request_history.len() > 100 {
            self.request_history.truncate(100);
        }
    }

    /// Add a proxy history entry (keeping max 500)
    pub fn add_proxy_history(&mut self, entry: ProxyHistoryEntry) {
        self.proxy_history.insert(0, entry);
        if self.proxy_history.len() > 500 {
            self.proxy_history.truncate(500);
        }
    }

    /// Clear old proxy history (older than specified duration)
    pub fn prune_proxy_history(&mut self, max_age: Duration) {
        let cutoff = SystemTime::now() - max_age;
        self.proxy_history.retain(|e| e.timestamp > cutoff);
    }
}

/// Request history entry (simplified for persistence)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: SystemTime,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub response_size: Option<usize>,
    /// Request headers (for replay)
    pub headers: Vec<(String, String)>,
    /// Request body (for replay)
    pub body: Option<String>,
}

impl HistoryEntry {
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            method: method.to_string(),
            url: url.to_string(),
            status: None,
            duration_ms: None,
            response_size: None,
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn with_response(mut self, status: u16, duration_ms: u64, response_size: usize) -> Self {
        self.status = Some(status);
        self.duration_ms = Some(duration_ms);
        self.response_size = Some(response_size);
        self
    }

    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_body(mut self, body: String) -> Self {
        self.body = Some(body);
        self
    }
}

/// Proxy history entry (simplified for persistence)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHistoryEntry {
    pub timestamp: SystemTime,
    pub method: String,
    pub url: String,
    pub host: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub response_size: Option<usize>,
    pub is_https: bool,
}

/// Environment with variables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub name: String,
    pub variables: Vec<Variable>,
}

impl Environment {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            variables: Vec::new(),
        }
    }

    pub fn with_variable(mut self, key: &str, value: &str, is_secret: bool) -> Self {
        self.variables.push(Variable {
            key: key.to_string(),
            value: value.to_string(),
            is_secret,
            enabled: true,
        });
        self
    }

    pub fn default_local() -> Self {
        Self::new("Local")
            .with_variable("BASE_URL", "http://localhost:8000", false)
            .with_variable("API_KEY", "", true)
    }

    pub fn default_dev() -> Self {
        Self::new("Development")
            .with_variable("BASE_URL", "https://dev.example.com", false)
            .with_variable("API_KEY", "", true)
    }

    pub fn default_staging() -> Self {
        Self::new("Staging")
            .with_variable("BASE_URL", "https://staging.example.com", false)
            .with_variable("API_KEY", "", true)
    }

    pub fn default_prod() -> Self {
        Self::new("Production")
            .with_variable("BASE_URL", "https://api.example.com", false)
            .with_variable("API_KEY", "", true)
    }

    /// Get a variable value by key
    pub fn get(&self, key: &str) -> Option<&str> {
        self.variables
            .iter()
            .find(|v| v.key == key && v.enabled)
            .map(|v| v.value.as_str())
    }

    /// Set a variable value
    pub fn set(&mut self, key: &str, value: &str) {
        if let Some(var) = self.variables.iter_mut().find(|v| v.key == key) {
            var.value = value.to_string();
        } else {
            self.variables.push(Variable {
                key: key.to_string(),
                value: value.to_string(),
                is_secret: false,
                enabled: true,
            });
        }
    }
}

/// Environment variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub key: String,
    pub value: String,
    pub is_secret: bool,
    pub enabled: bool,
}

/// Layout state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutState {
    /// Workspace panel width percentage
    pub workspace_width: u16,
    /// Request panel height percentage
    pub request_height: u16,
    /// Whether proxy details are shown
    pub show_proxy_details: bool,
}

impl Default for LayoutState {
    fn default() -> Self {
        Self {
            workspace_width: 25,
            request_height: 50,
            show_proxy_details: false,
        }
    }
}

/// Session manager for auto-save functionality
pub struct SessionManager {
    /// Current session data
    pub session: SessionData,
    /// Whether there are unsaved changes
    pub dirty: bool,
    /// Last save time
    pub last_save: Option<SystemTime>,
    /// Auto-save interval
    pub auto_save_interval: Duration,
}

impl SessionManager {
    /// Create a new session manager, loading existing session
    pub fn new() -> Self {
        Self {
            session: SessionData::load_or_default(),
            dirty: false,
            last_save: None,
            auto_save_interval: Duration::from_secs(60), // Auto-save every minute
        }
    }

    /// Mark session as dirty (has unsaved changes)
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Check if auto-save is needed and save if so
    pub fn maybe_auto_save(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }

        let should_save = match self.last_save {
            Some(last) => {
                SystemTime::now()
                    .duration_since(last)
                    .unwrap_or(Duration::ZERO)
                    >= self.auto_save_interval
            }
            None => true,
        };

        if should_save {
            self.save()?;
        }

        Ok(())
    }

    /// Save the session
    pub fn save(&mut self) -> Result<()> {
        self.session.save_default()?;
        self.dirty = false;
        self.last_save = Some(SystemTime::now());
        Ok(())
    }

    /// Force save (for shutdown)
    pub fn shutdown_save(&mut self) -> Result<()> {
        if self.dirty {
            self.save()?;
        }
        Ok(())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_session_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_session.json");

        let mut session = SessionData::new();
        session.add_history(HistoryEntry::new("GET", "https://example.com"));
        session.last_url = Some("https://test.com".to_string());

        session.save(&path).unwrap();
        assert!(path.exists());

        let loaded = SessionData::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.request_history.len(), 1);
        assert_eq!(loaded.last_url, Some("https://test.com".to_string()));
    }

    #[test]
    fn test_history_limit() {
        let mut session = SessionData::new();

        for i in 0..150 {
            session.add_history(HistoryEntry::new("GET", &format!("https://example.com/{}", i)));
        }

        assert_eq!(session.request_history.len(), 100);
        // Most recent should be first
        assert!(session.request_history[0].url.ends_with("/149"));
    }

    #[test]
    fn test_environment_variables() {
        let mut env = Environment::new("Test");
        env.set("API_KEY", "secret123");

        assert_eq!(env.get("API_KEY"), Some("secret123"));
        assert_eq!(env.get("MISSING"), None);
    }

    #[test]
    fn test_default_environments() {
        let session = SessionData::default();
        assert_eq!(session.environments.len(), 4);
        assert_eq!(session.environments[0].name, "Local");
        assert_eq!(session.environments[1].name, "Development");
    }
}
