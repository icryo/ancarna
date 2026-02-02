//! WebSocket Interception Module
//!
//! Handles WebSocket connection upgrades and message interception
//! for security analysis and debugging.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;

/// Direction of a WebSocket message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDirection {
    /// Message from client to server
    ClientToServer,
    /// Message from server to client
    ServerToClient,
}

impl MessageDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageDirection::ClientToServer => "→",
            MessageDirection::ServerToClient => "←",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            MessageDirection::ClientToServer => "Client → Server",
            MessageDirection::ServerToClient => "Server → Client",
        }
    }
}

/// Type of WebSocket message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

impl MessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageType::Text => "Text",
            MessageType::Binary => "Binary",
            MessageType::Ping => "Ping",
            MessageType::Pong => "Pong",
            MessageType::Close => "Close",
        }
    }
}

impl From<&Message> for MessageType {
    fn from(msg: &Message) -> Self {
        match msg {
            Message::Text(_) => MessageType::Text,
            Message::Binary(_) => MessageType::Binary,
            Message::Ping(_) => MessageType::Ping,
            Message::Pong(_) => MessageType::Pong,
            Message::Close(_) => MessageType::Close,
            Message::Frame(_) => MessageType::Binary,
        }
    }
}

/// A captured WebSocket message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    /// Unique message ID
    pub id: u64,
    /// Session ID this message belongs to
    pub session_id: u64,
    /// Message direction
    pub direction: MessageDirection,
    /// Message type
    pub message_type: MessageType,
    /// Message payload (text or hex-encoded binary)
    pub payload: String,
    /// Raw payload size in bytes
    pub size: usize,
    /// Timestamp when message was captured
    pub timestamp: DateTime<Utc>,
    /// Whether payload is hex-encoded binary
    pub is_binary: bool,
}

impl WebSocketMessage {
    /// Create a new message from a tungstenite Message
    pub fn from_message(
        msg: &Message,
        session_id: u64,
        direction: MessageDirection,
        id: u64,
    ) -> Self {
        let (payload, is_binary, size) = match msg {
            Message::Text(text) => (text.clone(), false, text.len()),
            Message::Binary(data) => (hex::encode(data), true, data.len()),
            Message::Ping(data) => (hex::encode(data), true, data.len()),
            Message::Pong(data) => (hex::encode(data), true, data.len()),
            Message::Close(frame) => {
                if let Some(cf) = frame {
                    (format!("{}: {}", cf.code, cf.reason), false, cf.reason.len())
                } else {
                    ("Connection closed".to_string(), false, 0)
                }
            }
            Message::Frame(_) => ("Raw frame".to_string(), false, 0),
        };

        Self {
            id,
            session_id,
            direction,
            message_type: MessageType::from(msg),
            payload,
            size,
            timestamp: Utc::now(),
            is_binary,
        }
    }

    /// Get a display-friendly payload (truncated if needed)
    pub fn display_payload(&self, max_len: usize) -> String {
        if self.payload.len() > max_len {
            // Find safe char boundary
            let mut end = max_len;
            while end > 0 && !self.payload.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &self.payload[..end])
        } else {
            self.payload.clone()
        }
    }

    /// Try to parse payload as JSON and pretty-print
    pub fn pretty_payload(&self) -> String {
        if self.is_binary {
            // Format hex in groups
            self.payload
                .as_bytes()
                .chunks(32)
                .map(|chunk| String::from_utf8_lossy(chunk).to_string())
                .collect::<Vec<_>>()
                .join("\n")
        } else if let Ok(json) = serde_json::from_str::<serde_json::Value>(&self.payload) {
            serde_json::to_string_pretty(&json).unwrap_or_else(|_| self.payload.clone())
        } else {
            self.payload.clone()
        }
    }
}

/// WebSocket session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Connecting,
    Open,
    Closing,
    Closed,
}

impl SessionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionState::Connecting => "Connecting",
            SessionState::Open => "Open",
            SessionState::Closing => "Closing",
            SessionState::Closed => "Closed",
        }
    }
}

/// A WebSocket connection session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketSession {
    /// Unique session ID
    pub id: u64,
    /// WebSocket URL (ws:// or wss://)
    pub url: String,
    /// Host
    pub host: String,
    /// Session state
    pub state: SessionState,
    /// Number of messages sent (client to server)
    pub messages_sent: usize,
    /// Number of messages received (server to client)
    pub messages_received: usize,
    /// Total bytes sent
    pub bytes_sent: usize,
    /// Total bytes received
    pub bytes_received: usize,
    /// Connection start time
    pub started_at: DateTime<Utc>,
    /// Connection end time (if closed)
    pub ended_at: Option<DateTime<Utc>>,
    /// Origin header (if present)
    pub origin: Option<String>,
    /// Subprotocol (if negotiated)
    pub subprotocol: Option<String>,
}

impl WebSocketSession {
    /// Create a new session
    pub fn new(id: u64, url: &str, host: &str) -> Self {
        Self {
            id,
            url: url.to_string(),
            host: host.to_string(),
            state: SessionState::Connecting,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            started_at: Utc::now(),
            ended_at: None,
            origin: None,
            subprotocol: None,
        }
    }

    /// Mark session as open
    pub fn mark_open(&mut self) {
        self.state = SessionState::Open;
    }

    /// Mark session as closed
    pub fn mark_closed(&mut self) {
        self.state = SessionState::Closed;
        self.ended_at = Some(Utc::now());
    }

    /// Record a sent message
    pub fn record_sent(&mut self, size: usize) {
        self.messages_sent += 1;
        self.bytes_sent += size;
    }

    /// Record a received message
    pub fn record_received(&mut self, size: usize) {
        self.messages_received += 1;
        self.bytes_received += size;
    }

    /// Get session duration
    pub fn duration_str(&self) -> String {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        let duration = end.signed_duration_since(self.started_at);
        let secs = duration.num_seconds();
        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        }
    }
}

/// WebSocket history manager
pub struct WebSocketHistory {
    /// Active sessions
    sessions: RwLock<VecDeque<WebSocketSession>>,
    /// All messages across sessions
    messages: RwLock<VecDeque<WebSocketMessage>>,
    /// Maximum number of sessions to keep
    max_sessions: usize,
    /// Maximum number of messages to keep
    max_messages: usize,
    /// Next session ID
    next_session_id: AtomicU64,
    /// Next message ID
    next_message_id: AtomicU64,
}

impl Default for WebSocketHistory {
    fn default() -> Self {
        Self::new(100, 10000)
    }
}

impl WebSocketHistory {
    /// Create a new history manager
    pub fn new(max_sessions: usize, max_messages: usize) -> Self {
        Self {
            sessions: RwLock::new(VecDeque::new()),
            messages: RwLock::new(VecDeque::new()),
            max_sessions,
            max_messages,
            next_session_id: AtomicU64::new(1),
            next_message_id: AtomicU64::new(1),
        }
    }

    /// Create a new session and return its ID
    pub fn create_session(&self, url: &str, host: &str) -> u64 {
        let id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        let session = WebSocketSession::new(id, url, host);

        let mut sessions = self.sessions.write();
        sessions.push_back(session);

        // Trim old sessions
        while sessions.len() > self.max_sessions {
            sessions.pop_front();
        }

        id
    }

    /// Update a session
    pub fn update_session<F>(&self, session_id: u64, f: F)
    where
        F: FnOnce(&mut WebSocketSession),
    {
        let mut sessions = self.sessions.write();
        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
            f(session);
        }
    }

    /// Add a message to history
    pub fn add_message(&self, msg: &Message, session_id: u64, direction: MessageDirection) -> u64 {
        let id = self.next_message_id.fetch_add(1, Ordering::SeqCst);
        let ws_msg = WebSocketMessage::from_message(msg, session_id, direction, id);

        // Update session stats
        self.update_session(session_id, |session| {
            match direction {
                MessageDirection::ClientToServer => session.record_sent(ws_msg.size),
                MessageDirection::ServerToClient => session.record_received(ws_msg.size),
            }
        });

        let mut messages = self.messages.write();
        messages.push_back(ws_msg);

        // Trim old messages
        while messages.len() > self.max_messages {
            messages.pop_front();
        }

        id
    }

    /// Get all sessions
    pub fn get_sessions(&self) -> Vec<WebSocketSession> {
        self.sessions.read().iter().cloned().collect()
    }

    /// Get messages for a session
    pub fn get_session_messages(&self, session_id: u64) -> Vec<WebSocketMessage> {
        self.messages
            .read()
            .iter()
            .filter(|m| m.session_id == session_id)
            .cloned()
            .collect()
    }

    /// Get recent messages across all sessions
    pub fn get_recent_messages(&self, limit: usize) -> Vec<WebSocketMessage> {
        let messages = self.messages.read();
        messages.iter().rev().take(limit).cloned().collect()
    }

    /// Get a specific session
    pub fn get_session(&self, session_id: u64) -> Option<WebSocketSession> {
        self.sessions.read().iter().find(|s| s.id == session_id).cloned()
    }

    /// Get total message count
    pub fn message_count(&self) -> usize {
        self.messages.read().len()
    }

    /// Get active session count
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .read()
            .iter()
            .filter(|s| s.state == SessionState::Open)
            .count()
    }

    /// Clear all history
    pub fn clear(&self) {
        self.sessions.write().clear();
        self.messages.write().clear();
    }
}

/// WebSocket filter for searching/filtering messages
#[derive(Debug, Default, Clone)]
pub struct WebSocketFilter {
    /// Filter by session ID
    pub session_id: Option<u64>,
    /// Filter by direction
    pub direction: Option<MessageDirection>,
    /// Filter by message type
    pub message_type: Option<MessageType>,
    /// Filter by payload content
    pub payload_contains: Option<String>,
    /// Filter by host
    pub host_contains: Option<String>,
}

impl WebSocketFilter {
    pub fn matches_message(&self, msg: &WebSocketMessage, session: Option<&WebSocketSession>) -> bool {
        if let Some(sid) = self.session_id {
            if msg.session_id != sid {
                return false;
            }
        }

        if let Some(dir) = self.direction {
            if msg.direction != dir {
                return false;
            }
        }

        if let Some(mt) = self.message_type {
            if msg.message_type != mt {
                return false;
            }
        }

        if let Some(ref text) = self.payload_contains {
            if !msg.payload.to_lowercase().contains(&text.to_lowercase()) {
                return false;
            }
        }

        if let Some(ref host) = self.host_contains {
            if let Some(s) = session {
                if !s.host.to_lowercase().contains(&host.to_lowercase()) {
                    return false;
                }
            }
        }

        true
    }

    pub fn is_empty(&self) -> bool {
        self.session_id.is_none()
            && self.direction.is_none()
            && self.message_type.is_none()
            && self.payload_contains.is_none()
            && self.host_contains.is_none()
    }
}

/// Check if an HTTP request is a WebSocket upgrade
pub fn is_websocket_upgrade(headers: &[(String, String)]) -> bool {
    let mut has_upgrade = false;
    let mut has_websocket = false;

    for (name, value) in headers {
        let name_lower = name.to_lowercase();
        let value_lower = value.to_lowercase();

        if name_lower == "upgrade" && value_lower == "websocket" {
            has_websocket = true;
        }
        if name_lower == "connection" && value_lower.contains("upgrade") {
            has_upgrade = true;
        }
    }

    has_upgrade && has_websocket
}

/// Extract the WebSocket URL from request
pub fn extract_websocket_url(host: &str, path: &str, is_tls: bool) -> String {
    let scheme = if is_tls { "wss" } else { "ws" };
    format!("{}://{}{}", scheme, host, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_direction() {
        assert_eq!(MessageDirection::ClientToServer.as_str(), "→");
        assert_eq!(MessageDirection::ServerToClient.as_str(), "←");
    }

    #[test]
    fn test_message_type() {
        assert_eq!(MessageType::Text.as_str(), "Text");
        assert_eq!(MessageType::Binary.as_str(), "Binary");
    }

    #[test]
    fn test_websocket_message_from_text() {
        let msg = Message::Text("hello world".to_string());
        let ws_msg = WebSocketMessage::from_message(&msg, 1, MessageDirection::ClientToServer, 1);

        assert_eq!(ws_msg.payload, "hello world");
        assert_eq!(ws_msg.message_type, MessageType::Text);
        assert!(!ws_msg.is_binary);
    }

    #[test]
    fn test_websocket_message_from_binary() {
        let msg = Message::Binary(vec![0x01, 0x02, 0x03]);
        let ws_msg = WebSocketMessage::from_message(&msg, 1, MessageDirection::ServerToClient, 1);

        assert_eq!(ws_msg.payload, "010203");
        assert_eq!(ws_msg.message_type, MessageType::Binary);
        assert!(ws_msg.is_binary);
    }

    #[test]
    fn test_session_stats() {
        let mut session = WebSocketSession::new(1, "wss://example.com/ws", "example.com");
        session.mark_open();

        session.record_sent(100);
        session.record_sent(200);
        session.record_received(500);

        assert_eq!(session.messages_sent, 2);
        assert_eq!(session.messages_received, 1);
        assert_eq!(session.bytes_sent, 300);
        assert_eq!(session.bytes_received, 500);
    }

    #[test]
    fn test_history() {
        let history = WebSocketHistory::new(10, 100);

        let session_id = history.create_session("wss://example.com/ws", "example.com");
        assert_eq!(session_id, 1);

        let msg = Message::Text("test".to_string());
        history.add_message(&msg, session_id, MessageDirection::ClientToServer);

        let messages = history.get_session_messages(session_id);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, "test");
    }

    #[test]
    fn test_is_websocket_upgrade() {
        let headers = vec![
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
        ];
        assert!(is_websocket_upgrade(&headers));

        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_extract_websocket_url() {
        assert_eq!(
            extract_websocket_url("example.com", "/ws", true),
            "wss://example.com/ws"
        );
        assert_eq!(
            extract_websocket_url("localhost:8080", "/socket", false),
            "ws://localhost:8080/socket"
        );
    }

    #[test]
    fn test_filter() {
        let filter = WebSocketFilter {
            direction: Some(MessageDirection::ClientToServer),
            ..Default::default()
        };

        let msg1 = WebSocketMessage {
            id: 1,
            session_id: 1,
            direction: MessageDirection::ClientToServer,
            message_type: MessageType::Text,
            payload: "test".to_string(),
            size: 4,
            timestamp: Utc::now(),
            is_binary: false,
        };

        let msg2 = WebSocketMessage {
            id: 2,
            session_id: 1,
            direction: MessageDirection::ServerToClient,
            message_type: MessageType::Text,
            payload: "response".to_string(),
            size: 8,
            timestamp: Utc::now(),
            is_binary: false,
        };

        assert!(filter.matches_message(&msg1, None));
        assert!(!filter.matches_message(&msg2, None));
    }
}
