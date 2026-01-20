//! Application event handling

use crossterm::event::{self, Event, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::proxy::InterceptedRequest;
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

    /// Response intercepted by proxy
    ProxyResponse(InterceptedRequest),

    /// Scan progress update (0.0 - 1.0)
    ScanProgress(f64),

    /// Scan completed with findings
    ScanComplete(Vec<Finding>),

    /// Spider found new URL
    SpiderUrl(String),

    /// Error occurred
    Error(String),

    /// Status message
    Status(String),

    /// Workspace changed
    WorkspaceChanged,

    /// Request completed
    RequestComplete {
        request_id: String,
        status: u16,
        duration_ms: u64,
    },
}

/// Handles terminal events and converts them to AppEvents
pub struct EventHandler {
    /// Event sender
    tx: mpsc::Sender<AppEvent>,

    /// Tick rate for periodic updates
    tick_rate: Duration,
}

impl EventHandler {
    /// Create a new event handler
    pub fn new(tx: mpsc::Sender<AppEvent>) -> Self {
        Self {
            tx,
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

    /// Send an event
    pub async fn send(&self, event: AppEvent) -> Result<(), mpsc::error::SendError<AppEvent>> {
        self.tx.send(event).await
    }
}

/// Event dispatcher for routing events to handlers
pub struct EventDispatcher {
    handlers: Vec<Box<dyn EventHandlerTrait + Send + Sync>>,
}

/// Trait for event handlers
#[async_trait::async_trait]
pub trait EventHandlerTrait {
    /// Handle an event, return true if consumed
    async fn handle(&mut self, event: &AppEvent) -> bool;
}

impl EventDispatcher {
    /// Create a new event dispatcher
    pub fn new() -> Self {
        Self { handlers: vec![] }
    }

    /// Register an event handler
    pub fn register(&mut self, handler: Box<dyn EventHandlerTrait + Send + Sync>) {
        self.handlers.push(handler);
    }

    /// Dispatch an event to all handlers
    pub async fn dispatch(&mut self, event: &AppEvent) -> bool {
        for handler in &mut self.handlers {
            if handler.handle(event).await {
                return true;
            }
        }
        false
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}
