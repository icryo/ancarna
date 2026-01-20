//! Proxy request/response history

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// A single entry in the proxy history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unique ID
    pub id: u64,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// HTTP method
    pub method: String,

    /// Request URL
    pub url: String,

    /// Host
    pub host: String,

    /// Path
    pub path: String,

    /// HTTP status code (None if request not yet completed)
    pub status: Option<u16>,

    /// Response time in milliseconds
    pub duration_ms: Option<u64>,

    /// Request size in bytes
    pub request_size: usize,

    /// Response size in bytes
    pub response_size: Option<usize>,

    /// Request headers
    pub request_headers: HashMap<String, String>,

    /// Response headers
    pub response_headers: Option<HashMap<String, String>>,

    /// Request body
    pub request_body: Option<Vec<u8>>,

    /// Response body
    pub response_body: Option<Vec<u8>>,

    /// Content type of response
    pub content_type: Option<String>,

    /// Whether the request was intercepted/modified
    pub intercepted: bool,

    /// Whether this is a TLS connection
    pub is_https: bool,

    /// Tags/labels for filtering
    pub tags: Vec<String>,

    /// Notes added by user
    pub notes: Option<String>,

    /// Highlight color
    pub highlight: Option<String>,
}

impl HistoryEntry {
    pub fn new(id: u64, method: &str, url: &str) -> Self {
        let parsed = url::Url::parse(url).ok();
        let host = parsed
            .as_ref()
            .and_then(|u| u.host_str())
            .unwrap_or("")
            .to_string();
        let path = parsed
            .as_ref()
            .map(|u| u.path())
            .unwrap_or("/")
            .to_string();
        let is_https = parsed
            .as_ref()
            .map(|u| u.scheme() == "https")
            .unwrap_or(false);

        Self {
            id,
            timestamp: Utc::now(),
            method: method.to_string(),
            url: url.to_string(),
            host,
            path,
            status: None,
            duration_ms: None,
            request_size: 0,
            response_size: None,
            request_headers: HashMap::new(),
            response_headers: None,
            request_body: None,
            response_body: None,
            content_type: None,
            intercepted: false,
            is_https,
            tags: Vec::new(),
            notes: None,
            highlight: None,
        }
    }
}

/// Proxy history manager
pub struct ProxyHistory {
    /// All history entries
    entries: Arc<RwLock<Vec<HistoryEntry>>>,

    /// Next ID counter
    next_id: Arc<RwLock<u64>>,

    /// Maximum number of entries to keep
    max_entries: usize,
}

impl ProxyHistory {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(RwLock::new(1)),
            max_entries,
        }
    }

    /// Add a new request to history
    pub fn add_request(&self, method: &str, url: &str) -> u64 {
        let mut next_id = self.next_id.write();
        let id = *next_id;
        *next_id += 1;

        let entry = HistoryEntry::new(id, method, url);

        let mut entries = self.entries.write();
        entries.push(entry);

        // Trim if over limit
        if entries.len() > self.max_entries {
            entries.remove(0);
        }

        id
    }

    /// Update an entry with request details (headers and body)
    pub fn update_request(
        &self,
        id: u64,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
    ) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.request_size = body.as_ref().map(|b| b.len()).unwrap_or(0);
            entry.request_headers = headers;
            entry.request_body = body;
        }
    }

    /// Update an entry with response information
    pub fn update_response(
        &self,
        id: u64,
        status: u16,
        duration_ms: u64,
        response_size: usize,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
    ) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.status = Some(status);
            entry.duration_ms = Some(duration_ms);
            entry.response_size = Some(response_size);
            entry.response_headers = Some(headers.clone());
            entry.response_body = body;
            entry.content_type = headers.get("content-type").cloned();
        }
    }

    /// Get all entries
    pub fn get_all(&self) -> Vec<HistoryEntry> {
        self.entries.read().clone()
    }

    /// Get entry by ID
    pub fn get(&self, id: u64) -> Option<HistoryEntry> {
        self.entries.read().iter().find(|e| e.id == id).cloned()
    }

    /// Filter entries by host
    pub fn filter_by_host(&self, host: &str) -> Vec<HistoryEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.host.contains(host))
            .cloned()
            .collect()
    }

    /// Filter entries by status code
    pub fn filter_by_status(&self, status: u16) -> Vec<HistoryEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.status == Some(status))
            .cloned()
            .collect()
    }

    /// Search entries by URL or body content
    pub fn search(&self, query: &str) -> Vec<HistoryEntry> {
        let query = query.to_lowercase();
        self.entries
            .read()
            .iter()
            .filter(|e| {
                e.url.to_lowercase().contains(&query)
                    || e.request_body
                        .as_ref()
                        .map(|b| String::from_utf8_lossy(b).to_lowercase().contains(&query))
                        .unwrap_or(false)
                    || e.response_body
                        .as_ref()
                        .map(|b| String::from_utf8_lossy(b).to_lowercase().contains(&query))
                        .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Clear all history
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Check if history is empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Add tag to entry
    pub fn add_tag(&self, id: u64, tag: &str) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            if !entry.tags.contains(&tag.to_string()) {
                entry.tags.push(tag.to_string());
            }
        }
    }

    /// Set note on entry
    pub fn set_note(&self, id: u64, note: &str) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.notes = Some(note.to_string());
        }
    }

    /// Set highlight color
    pub fn set_highlight(&self, id: u64, color: &str) {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.highlight = Some(color.to_string());
        }
    }
}

impl Default for ProxyHistory {
    fn default() -> Self {
        Self::new(10000)
    }
}
