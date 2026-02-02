//! Web spider/crawler module
//!
//! Provides web crawling capabilities for discovering application structure.

use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use parking_lot::RwLock;

use crate::http::HttpClient;

/// Spider configuration
#[derive(Debug, Clone)]
pub struct SpiderConfig {
    /// Maximum depth to crawl
    pub max_depth: usize,

    /// Maximum pages to crawl
    pub max_pages: usize,

    /// Delay between requests in milliseconds
    pub delay_ms: u64,

    /// Follow redirects
    pub follow_redirects: bool,

    /// Parse JavaScript for URLs (basic)
    pub parse_js: bool,

    /// Respect robots.txt
    pub respect_robots: bool,

    /// URL patterns to exclude
    pub exclude_patterns: Vec<String>,

    /// URL patterns to include (if empty, include all)
    pub include_patterns: Vec<String>,
}

impl Default for SpiderConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_pages: 1000,
            delay_ms: 100,
            follow_redirects: true,
            parse_js: false,
            respect_robots: true,
            exclude_patterns: vec![
                r"\.pdf$".to_string(),
                r"\.zip$".to_string(),
                r"\.png$".to_string(),
                r"\.jpg$".to_string(),
                r"\.gif$".to_string(),
                r"logout".to_string(),
            ],
            include_patterns: Vec::new(),
        }
    }
}

/// Spider state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiderState {
    Idle,
    Running,
    Paused,
    Stopped,
}

/// A discovered URL
#[derive(Debug, Clone)]
pub struct DiscoveredUrl {
    /// The URL
    pub url: String,

    /// Depth from start URL
    pub depth: usize,

    /// Source URL
    pub source: Option<String>,

    /// Link text (if any)
    pub link_text: Option<String>,
}

/// Web spider
pub struct Spider {
    /// Configuration
    config: SpiderConfig,

    /// Visited URLs
    visited: Arc<RwLock<HashSet<String>>>,

    /// Queue of URLs to visit
    queue: Arc<RwLock<VecDeque<DiscoveredUrl>>>,

    /// All discovered URLs
    discovered: Arc<RwLock<Vec<DiscoveredUrl>>>,

    /// Current state
    state: Arc<RwLock<SpiderState>>,

    /// Scope (base URL)
    scope: Option<String>,
}

impl Spider {
    /// Create a new spider
    pub fn new(config: SpiderConfig) -> Self {
        Self {
            config,
            visited: Arc::new(RwLock::new(HashSet::new())),
            queue: Arc::new(RwLock::new(VecDeque::new())),
            discovered: Arc::new(RwLock::new(Vec::new())),
            state: Arc::new(RwLock::new(SpiderState::Idle)),
            scope: None,
        }
    }

    /// Start crawling from a URL
    pub async fn crawl(&mut self, start_url: &str, client: &HttpClient) -> Result<Vec<DiscoveredUrl>> {
        // Set scope to the start URL's origin
        let parsed = url::Url::parse(start_url)?;
        self.scope = Some(format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or("")));

        // Initialize queue
        {
            let mut queue = self.queue.write();
            queue.push_back(DiscoveredUrl {
                url: start_url.to_string(),
                depth: 0,
                source: None,
                link_text: None,
            });
        }

        *self.state.write() = SpiderState::Running;

        while *self.state.read() == SpiderState::Running {
            let next = {
                let mut queue = self.queue.write();
                queue.pop_front()
            };

            let item = match next {
                Some(item) => item,
                None => break, // Queue empty
            };

            // Check if already visited
            {
                let visited = self.visited.read();
                if visited.contains(&item.url) {
                    continue;
                }
            }

            // Check depth limit
            if item.depth > self.config.max_depth {
                continue;
            }

            // Check page limit
            if self.visited.read().len() >= self.config.max_pages {
                break;
            }

            // Check if URL is in scope
            if !self.is_in_scope(&item.url) {
                continue;
            }

            // Mark as visited
            self.visited.write().insert(item.url.clone());
            self.discovered.write().push(item.clone());

            // Fetch the page
            let response = match client.get(&item.url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Only parse HTML responses
            if !response.is_html() {
                continue;
            }

            // Extract links
            let body = response.body_text();
            let links = extract_links(&body, &item.url);

            // Add new links to queue
            {
                let mut queue = self.queue.write();
                let visited = self.visited.read();

                for link in links {
                    if !visited.contains(&link) && self.should_crawl(&link) {
                        queue.push_back(DiscoveredUrl {
                            url: link,
                            depth: item.depth + 1,
                            source: Some(item.url.clone()),
                            link_text: None,
                        });
                    }
                }
            }

            // Delay between requests
            if self.config.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.config.delay_ms)).await;
            }
        }

        *self.state.write() = SpiderState::Idle;

        Ok(self.discovered.read().clone())
    }

    /// Check if URL is in scope
    fn is_in_scope(&self, url: &str) -> bool {
        match &self.scope {
            Some(scope) => url.starts_with(scope),
            None => true,
        }
    }

    /// Check if URL should be crawled based on patterns
    fn should_crawl(&self, url: &str) -> bool {
        // Check exclude patterns
        for pattern in &self.config.exclude_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if regex.is_match(url) {
                    return false;
                }
            }
        }

        // Check include patterns (if any)
        if !self.config.include_patterns.is_empty() {
            for pattern in &self.config.include_patterns {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    if regex.is_match(url) {
                        return true;
                    }
                }
            }
            return false;
        }

        true
    }

    /// Stop crawling
    pub fn stop(&self) {
        *self.state.write() = SpiderState::Stopped;
    }

    /// Pause crawling
    pub fn pause(&self) {
        if *self.state.read() == SpiderState::Running {
            *self.state.write() = SpiderState::Paused;
        }
    }

    /// Resume crawling
    pub fn resume(&self) {
        if *self.state.read() == SpiderState::Paused {
            *self.state.write() = SpiderState::Running;
        }
    }

    /// Get current state
    pub fn state(&self) -> SpiderState {
        *self.state.read()
    }

    /// Get discovered URLs
    pub fn discovered(&self) -> Vec<DiscoveredUrl> {
        self.discovered.read().clone()
    }

    /// Get statistics
    pub fn stats(&self) -> SpiderStats {
        SpiderStats {
            visited: self.visited.read().len(),
            queued: self.queue.read().len(),
            discovered: self.discovered.read().len(),
        }
    }
}

/// Spider statistics
#[derive(Debug, Clone)]
pub struct SpiderStats {
    pub visited: usize,
    pub queued: usize,
    pub discovered: usize,
}

/// Extract links from HTML
fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();

    let base = match url::Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return links,
    };

    // Use scraper to parse HTML
    let document = scraper::Html::parse_document(html);

    // Extract href attributes
    let a_selector = scraper::Selector::parse("a[href]").unwrap();
    for element in document.select(&a_selector) {
        if let Some(href) = element.value().attr("href") {
            if let Ok(resolved) = base.join(href) {
                links.push(resolved.to_string());
            }
        }
    }

    // Extract form actions
    let form_selector = scraper::Selector::parse("form[action]").unwrap();
    for element in document.select(&form_selector) {
        if let Some(action) = element.value().attr("action") {
            if let Ok(resolved) = base.join(action) {
                links.push(resolved.to_string());
            }
        }
    }

    // Extract src attributes (scripts, iframes)
    let src_selector = scraper::Selector::parse("[src]").unwrap();
    for element in document.select(&src_selector) {
        if let Some(src) = element.value().attr("src") {
            if let Ok(resolved) = base.join(src) {
                links.push(resolved.to_string());
            }
        }
    }

    // Deduplicate
    links.sort();
    links.dedup();

    links
}
