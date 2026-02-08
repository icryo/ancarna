//! Application event handling

#![allow(dead_code)]

use crossterm::event::{self, Event, KeyEvent};
use std::time::Duration;

use crate::proxy::{HistoryEntry, InterceptedRequest};
use crate::scanner::Finding;

/// Application events
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Quit the application
    Quit,

    /// Keyboard input
    Key(KeyEvent),

    /// Terminal resize
    Resize(u16, u16),

    /// Tick for animations/updates
    Tick,

    /// Request intercepted by proxy
    ProxyRequest(InterceptedRequest),

    /// Proxy request/response completed (for passive scanning)
    ProxyComplete(HistoryEntry),

    /// Scan progress update (0.0 - 1.0)
    ScanProgress(f64),

    /// Scan completed with findings
    ScanComplete(Vec<Finding>),

    /// Error occurred
    Error(String),
}

/// Handles terminal events and converts them to AppEvents
pub struct EventHandler {
    /// Tick rate for periodic updates
    tick_rate: Duration,
}

impl EventHandler {
    /// Create a new event handler
    pub fn new() -> Self {
        Self {
            tick_rate: Duration::from_millis(100),
        }
    }

    /// Get the next event
    pub async fn next(&mut self) -> Option<AppEvent> {
        // Poll for terminal events
        if event::poll(self.tick_rate).ok()? {
            match event::read().ok()? {
                Event::Key(key) => Some(AppEvent::Key(key)),
                Event::Resize(width, height) => Some(AppEvent::Resize(width, height)),
                _ => Some(AppEvent::Tick),
            }
        } else {
            Some(AppEvent::Tick)
        }
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}
