//! Session and cookie management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Session manager for maintaining state across requests
#[derive(Debug, Clone, Default)]
pub struct Session {
    /// Cookies by domain
    cookies: HashMap<String, Vec<SessionCookie>>,

    /// Session variables (set by scripts)
    variables: HashMap<String, String>,

    /// Request history
    history: Vec<HistoryItem>,

    /// Maximum history items
    max_history: usize,
}

/// A cookie stored in the session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires: Option<DateTime<Utc>>,
    pub secure: bool,
    pub http_only: bool,
}

/// An item in the request history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub request_id: Option<String>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
            variables: HashMap::new(),
            history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Add or update a cookie
    pub fn set_cookie(&mut self, cookie: SessionCookie) {
        let domain_cookies = self.cookies.entry(cookie.domain.clone()).or_default();

        // Replace existing cookie with same name and path
        if let Some(existing) = domain_cookies
            .iter_mut()
            .find(|c| c.name == cookie.name && c.path == cookie.path)
        {
            *existing = cookie;
        } else {
            domain_cookies.push(cookie);
        }
    }

    /// Get cookies for a domain/path
    pub fn get_cookies(&self, domain: &str, path: &str) -> Vec<&SessionCookie> {
        let mut cookies = Vec::new();

        for (cookie_domain, domain_cookies) in &self.cookies {
            // Check if domain matches (including parent domains)
            if domain.ends_with(cookie_domain) || cookie_domain == domain {
                for cookie in domain_cookies {
                    // Check path
                    if path.starts_with(&cookie.path) {
                        // Check expiration
                        if cookie.expires.map(|e| e > Utc::now()).unwrap_or(true) {
                            cookies.push(cookie);
                        }
                    }
                }
            }
        }

        cookies
    }

    /// Get cookies as header value
    pub fn get_cookie_header(&self, domain: &str, path: &str) -> Option<String> {
        let cookies = self.get_cookies(domain, path);
        if cookies.is_empty() {
            None
        } else {
            Some(
                cookies
                    .iter()
                    .map(|c| format!("{}={}", c.name, c.value))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        }
    }

    /// Clear cookies for a domain
    pub fn clear_cookies(&mut self, domain: &str) {
        self.cookies.remove(domain);
    }

    /// Clear all cookies
    pub fn clear_all_cookies(&mut self) {
        self.cookies.clear();
    }

    /// Set a session variable
    pub fn set_variable(&mut self, name: &str, value: &str) {
        self.variables.insert(name.to_string(), value.to_string());
    }

    /// Get a session variable
    pub fn get_variable(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(|s| s.as_str())
    }

    /// Remove a session variable
    pub fn remove_variable(&mut self, name: &str) {
        self.variables.remove(name);
    }

    /// Clear all session variables
    pub fn clear_variables(&mut self) {
        self.variables.clear();
    }

    /// Add to history
    pub fn add_history(&mut self, item: HistoryItem) {
        self.history.push(item);

        // Trim history if over limit
        while self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    /// Get history
    pub fn history(&self) -> &[HistoryItem] {
        &self.history
    }

    /// Clear history
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Clear entire session
    pub fn clear(&mut self) {
        self.cookies.clear();
        self.variables.clear();
        self.history.clear();
    }
}

impl HistoryItem {
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            method: method.to_string(),
            url: url.to_string(),
            status: None,
            duration_ms: None,
            request_id: None,
        }
    }
}
